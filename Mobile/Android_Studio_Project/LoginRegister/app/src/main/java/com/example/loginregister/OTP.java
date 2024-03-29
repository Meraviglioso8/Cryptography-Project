package com.example.loginregister;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatButton;

public class OTP extends AppCompatActivity {

    private EditText otpEt1,otpEt2,otpEt3,otpEt4,otpEt5,otpEt6;
    private TextView resendBtn;

    private boolean resendEnabled = false;
    private int resendTime = 60;
    private int selectedETPosition = 0;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_otp);

        otpEt1 = findViewById(R.id.otpET1);
        otpEt2 = findViewById(R.id.otpET2);
        otpEt3 = findViewById(R.id.otpET3);
        otpEt4 = findViewById(R.id.otpET4);
        otpEt5 = findViewById(R.id.otpET5);
        otpEt6 = findViewById(R.id.otpET6);

        resendBtn = findViewById(R.id.reSendBtn);

        final TextView otpEmail = findViewById(R.id.otpMail);

        final String getEmail = getIntent().getStringExtra("email");

        final AppCompatButton verifyBtn = findViewById(R.id.verifyBtn);

        otpEmail.setText(getEmail);

        otpEt1.addTextChangedListener(textWatcher);
        otpEt2.addTextChangedListener(textWatcher);
        otpEt3.addTextChangedListener(textWatcher);
        otpEt4.addTextChangedListener(textWatcher);
        otpEt5.addTextChangedListener(textWatcher);
        otpEt6.addTextChangedListener(textWatcher);

        showKeyboard(otpEt1);

        startCountDown();

        resendBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if(resendEnabled){

                    startCountDown();
                }
            }
        });
        verifyBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                final String generateOTP = otpEt1.getText().toString()+otpEt2.getText().toString()+otpEt3.getText().toString()+otpEt4.getText().toString()+otpEt5.getText().toString()+otpEt6.getText().toString();

                if (generateOTP.length() == 6)
                {

                }

            }
        });
    }
    private void showKeyboard(EditText otpET){
        otpET.requestFocus();
        InputMethodManager inputMethodManager =(InputMethodManager) getSystemService((Context.INPUT_METHOD_SERVICE));
        inputMethodManager.showSoftInput(otpET, InputMethodManager.SHOW_IMPLICIT);

    }
    private void startCountDown(){
        resendEnabled = false;
        resendBtn.setTextColor(Color.parseColor("#99000000"));
        new CountDownTimer(resendTime*1000, 1000){

            @Override
            public void onTick(long l) {
                resendBtn.setText("Resend Code ("+(l/1000)+")");
            }

            @Override
            public void onFinish() {
                resendEnabled = true;
                resendBtn.setText("Resend Code");
                resendBtn.setTextColor(getResources().getColor(R.color.primary));

            }
        }.start();
    }
    private final TextWatcher textWatcher = new TextWatcher() {
        @Override
        public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {

        }

        @Override
        public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {

        }

        @Override
        public void afterTextChanged(Editable editable) {
            if(editable.length()>0){
                if (selectedETPosition == 0){
                    selectedETPosition = 1;
                    showKeyboard(otpEt2);
                }
                else if (selectedETPosition == 1){
                    selectedETPosition = 2;
                    showKeyboard(otpEt3);
                }
                else if (selectedETPosition == 2){
                    selectedETPosition = 3;
                    showKeyboard(otpEt4);
                }
                else if (selectedETPosition == 3){
                    selectedETPosition = 4;
                    showKeyboard(otpEt5);
                }
                else if (selectedETPosition == 4){
                    selectedETPosition = 5;
                    showKeyboard(otpEt6);
                }
            }
        }
    };

    @Override
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        if(keyCode == KeyEvent.KEYCODE_DEL){
            if (selectedETPosition == 5) {
                selectedETPosition = 4;
                showKeyboard(otpEt5);
            }
            if (selectedETPosition == 4) {
                selectedETPosition = 3;
                showKeyboard(otpEt4);
            }
            if (selectedETPosition == 3) {
                selectedETPosition = 2;
                showKeyboard(otpEt3);
            }
            if (selectedETPosition == 2) {
                selectedETPosition = 1;
                showKeyboard(otpEt2);
            }
            if (selectedETPosition == 1) {
                selectedETPosition = 0;
                showKeyboard(otpEt1);
            }
            return true;
        }
        else {
            return super.onKeyUp(keyCode, event);
        }

    }
}