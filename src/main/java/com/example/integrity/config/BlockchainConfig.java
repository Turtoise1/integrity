package com.example.integrity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;

@Configuration
public class BlockchainConfig {

    @Value("${blockchain.rpc.url:http://localhost:8545}")
    private String rpcUrl;

    @Value("${blockchain.deployer.private-key:}")
    private String deployerPrivateKey;

    @Bean
    public Web3j web3j() {
        return Web3j.build(new HttpService(rpcUrl));
    }

    @Bean
    public Credentials credentials() {
        if (deployerPrivateKey == null || deployerPrivateKey.isEmpty()) {
            throw new RuntimeException(
                    "Deployer private key is not configured. Please set blockchain.deployer.private-key in application.properties");
        }
        return Credentials.create(deployerPrivateKey);
    }
}
