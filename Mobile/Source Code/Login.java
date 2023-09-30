package com.example.loginregister;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.AppCompatButton;

import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.Scanner;


public class Login extends AppCompatActivity {


    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        ConnectPyTask task = new ConnectPyTask();
        ConnectPyTask.context = getApplicationContext();

        final EditText usernameET = findViewById(R.id.usernameET);
        final EditText passwordET = findViewById(R.id.passwordET);
        final TextView signUpBtn = findViewById(R.id.signUpBtn);
        final AppCompatButton signInBtn = findViewById(R.id.signInBtn);
        signUpBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(Login.this, Register.class));
            }
        });

        signInBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                startActivity(new Intent(Login.this, OTP.class));

            }
        });


    }
    static class ConnectPyTask extends AsyncTask<String, Void, String> {
        static Context context = null;
        static float startTime = 0, endTime = 0;

        @Override
        protected String doInBackground(String... data) {
            try {
                startTime = System.currentTimeMillis();
                Socket socket = new Socket("20.187.76.92", 9999); //Server IP and PORT

            } catch (Exception e) {
                Log.d("Exception", e.toString());
            }
            return null;
        }
    }
}
