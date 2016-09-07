package com.c_heo.cryptor;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.c_heo.cryptor.utils.Cryptor;

import java.security.GeneralSecurityException;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getSimpleName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {

            /**
             * crypt
             *
             * 形式：AES256
             */
            String aesKey = "FvRMx35LkmNxcP3N";
            String plainText = "plainText";

            String encTxt = Cryptor.Aes(aesKey).encode(plainText);
            Log.d(TAG, "encTxt # "+encTxt);

            String decTxt = Cryptor.Aes(aesKey).decode(encTxt);
            Log.d(TAG, "decTxt # "+decTxt);


            /**
             * hashing
             *
             * 形式：SHA256
             */
            String hashKey = "1t90hRR4xJmTN7Jv";
            String targetText = "targetText";

            String hasTxt = Cryptor.Sha(hashKey).hashing(targetText);
            Log.d(TAG, "hasTxt # "+hasTxt);

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

}
