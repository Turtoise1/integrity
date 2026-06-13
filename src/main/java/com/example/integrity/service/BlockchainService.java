package com.example.integrity.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.utils.Numeric;

import com.example.integrity.model.AnchorVerificationResult;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Slf4j
@Service
public class BlockchainService {

    private static final int DEFAULT_GAS_LIMIT = 6721975;

    @Autowired
    private Web3j web3j;

    @Autowired
    private Credentials credentials;

    @Autowired
    private DocumentService documentService;

    @Value("${blockchain.contract.address}")
    private String contractAddress;

    private MessageDigest sha256Digest;

    @PostConstruct
    public void init() {
        try {
            sha256Digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize SHA-256 digest", e);
        }
    }

    public String storeHash(String filePath) throws IOException {
        // Get file content and compute SHA-256 hash
        byte[] fileContent = documentService.getFileContent(filePath);
        byte[] hashBytes = sha256Digest.digest(fileContent);

        // Prepare the function call
        Function function = new Function(
                "storeHash",
                Arrays.asList(
                        new Utf8String(filePath),
                        new Bytes32(hashBytes)),
                Collections.emptyList());

        String encodedFunction = org.web3j.abi.FunctionEncoder.encode(function);

        // Get nonce
        BigInteger nonce = web3j.ethGetTransactionCount(credentials.getAddress(), DefaultBlockParameterName.LATEST)
                .send().getTransactionCount();

        // Get gas price
        BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();

        // Create raw transaction
        RawTransaction rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                BigInteger.valueOf(DEFAULT_GAS_LIMIT),
                contractAddress,
                BigInteger.ZERO,
                encodedFunction);

        // Sign transaction
        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
        String hexValue = Numeric.toHexString(signedMessage);

        // Send transaction
        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

        if (ethSendTransaction.hasError()) {
            throw new RuntimeException("Transaction error: " + ethSendTransaction.getError().getMessage());
        }

        String txHash = ethSendTransaction.getTransactionHash();
        String hexHash = Numeric.toHexString(hashBytes);

        log.info("Stored hash for file {} in blockchain, tx: {}", filePath, txHash);

        return txHash + ":" + hexHash;
    }

    public AnchorVerificationResult verifyHash(String filePath) throws IOException {
        // Get file content and compute current SHA-256 hash
        byte[] fileContent = documentService.getFileContent(filePath);
        byte[] currentHashBytes = sha256Digest.digest(fileContent);
        String currentHexHash = Numeric.toHexString(currentHashBytes);

        // Retrieve stored hash from blockchain
        Function function = new Function(
                "getHash",
                Arrays.asList(new Utf8String(filePath)),
                Arrays.asList(
                        new TypeReference<Bytes32>() {
                        },
                        new TypeReference<Uint256>() {
                        }));

        String encodedFunction = FunctionEncoder.encode(function);

        Transaction transaction = Transaction.createEthCallTransaction(credentials.getAddress(), contractAddress,
                encodedFunction);

        EthCall ethCall = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).send();

        if (ethCall.hasError()) {
            throw new RuntimeException("Call error: " + ethCall.getError().getMessage());
        }

        List<Type> results = org.web3j.abi.FunctionReturnDecoder.decode(ethCall.getValue(),
                function.getOutputParameters());

        if (results.isEmpty() || results.get(0).getValue() == null) {
            // No hash stored for this file
            return new AnchorVerificationResult(false, null, currentHexHash, null);
        }

        byte[] storedHashBytes = (byte[]) results.get(0).getValue();
        String storedHexHash = Numeric.toHexString(storedHashBytes);
        BigInteger timestamp = (BigInteger) results.get(1).getValue();

        boolean match = storedHexHash.equalsIgnoreCase(currentHexHash);

        return new AnchorVerificationResult(match, storedHexHash, currentHexHash, timestamp.longValue());
    }

    public List<String> listAnchoredFiles() throws IOException {
        Function function = new Function(
                "listFiles",
                Collections.emptyList(),
                Arrays.asList(new TypeReference<DynamicArray<Utf8String>>() {
                }));

        String encodedFunction = FunctionEncoder.encode(function);

        Transaction transaction = Transaction.createEthCallTransaction(credentials.getAddress(), contractAddress,
                encodedFunction);

        EthCall ethCall = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).send();

        if (ethCall.hasError()) {
            throw new RuntimeException("Call error: " + ethCall.getError().getMessage());
        }

        List<Type> results = FunctionReturnDecoder.decode(ethCall.getValue(),
                function.getOutputParameters());

        if (results.isEmpty() || results.get(0).getValue() == null) {
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        List<Utf8String> stringResults = (List<Utf8String>) results.get(0).getValue();
        List<String> filePaths = new ArrayList<>();
        for (Utf8String utf8Str : stringResults) {
            filePaths.add(utf8Str.getValue());
        }

        return filePaths;
    }

    public void setContractAddress(String address) {
        this.contractAddress = address;
    }
}
