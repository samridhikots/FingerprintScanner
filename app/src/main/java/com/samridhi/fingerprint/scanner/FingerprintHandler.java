package com.samridhi.fingerprint.scanner;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import androidx.core.content.ContextCompat;
import android.widget.ImageView;
import android.widget.TextView;

@TargetApi(Build.VERSION_CODES.M)

public class FingerprintHandler extends FingerprintManager.AuthenticationCallback {

    private Context context;

    public FingerprintHandler(Context context){

        this.context = context;

    }

    public void startAuth(FingerprintManager fingerprintManager, FingerprintManager.CryptoObject cryptoObject){

        CancellationSignal cancellationSignal = new CancellationSignal();
        fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);

    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {

        this.update("There was an Auth Error. " + errString, false);

    }

    @Override
    public void onAuthenticationFailed() {

        this.update("Auth Failed. ", false);

    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {

        this.update("Error: " + helpString, false);

    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {

        this.update("You can now access the app.", true);

    }

    private void update(String s, boolean b) {

        TextView textViewLabel = (TextView) ((Activity)context).findViewById(R.id.textViewLabel);
        ImageView imageView = (ImageView) ((Activity)context).findViewById(R.id.fingerprintImage);

        textViewLabel.setText(s);

        if(b == false){

            textViewLabel.setTextColor(ContextCompat.getColor(context, R.color.colorAccent));

        } else {

            textViewLabel.setTextColor(ContextCompat.getColor(context, R.color.colorPrimary));
            imageView.setImageResource(R.mipmap.action_done);

        }

    }
}
