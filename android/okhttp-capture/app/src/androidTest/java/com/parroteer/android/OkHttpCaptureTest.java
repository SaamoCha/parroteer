package com.parroteer.android;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

@RunWith(AndroidJUnit4.class)
public final class OkHttpCaptureTest {
    private static final String REFLECTOR_URL = "https://tls.browserleaks.com/";

    @Test
    public void captureBrowserLeaksTlsFingerprint() throws Exception {
        OkHttpClient client = new OkHttpClient.Builder()
                .protocols(Arrays.asList(Protocol.HTTP_2, Protocol.HTTP_1_1))
                .build();

        Request request = new Request.Builder()
                .url(REFLECTOR_URL)
                .build();

        try (Response response = client.newCall(request).execute()) {
            assertTrue("Unexpected HTTP status: " + response.code(), response.isSuccessful());

            ResponseBody responseBody = response.body();
            assertNotNull("BrowserLeaks response body is null", responseBody);

            String json = responseBody.string();
            JSONObject root = new JSONObject(json);
            assertTrue("BrowserLeaks response has no tls object", root.has("tls"));

            Context context = ApplicationProvider.getApplicationContext();
            File out = new File(context.getFilesDir(), "android-okhttp.json");
            try (FileOutputStream stream = new FileOutputStream(out)) {
                stream.write(json.getBytes(StandardCharsets.UTF_8));
                stream.write('\n');
            }

            System.out.println("PARROTEER_ANDROID_CAPTURE=" + out.getAbsolutePath());
        }
    }
}
