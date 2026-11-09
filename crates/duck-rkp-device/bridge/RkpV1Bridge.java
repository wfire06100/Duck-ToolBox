package duck.rkp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;

/** Calls the device's own stable AIDL proxy; owns no keys, network or output artifacts. */
public final class RkpV1Bridge {
    private static final String PREFIX = "android.hardware.security.keymint.";
    private static final String SERVICE = PREFIX + "IRemotelyProvisionedComponent";
    private static final int LIMIT = 0xa000;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("expected exchange directory");
        File directory = new File(args[0]);
        // Status 0: MAC, DeviceInfo, ProtectedData. Status 1: AIDL error code and message.
        // Status 2: transport error. Status 3: invalid HAL response.
        // Every byte string has a big-endian int length.
        byte[] response;
        try {
            response = request(directory);
        } catch (Throwable failure) {
            while (failure instanceof InvocationTargetException && failure.getCause() != null) {
                failure = failure.getCause();
            }
            if (failure.getClass().getName().equals("android.os.ServiceSpecificException")) {
                int code = failure.getClass().getField("errorCode").getInt(failure);
                response = errorReply(1, code, failure.toString());
            } else {
                response = errorReply(2, 0, failure.toString());
            }
        }
        try (FileOutputStream file = new FileOutputStream(new File(directory, "reply.bin"))) {
            file.write(response);
        }
    }

    private static byte[] request(File directory) throws Exception {
        byte[] challenge, maced, p256, x25519;
        try (DataInputStream input = new DataInputStream(
                new FileInputStream(new File(directory, "request.bin")))) {
            challenge = readBytes(input);
            maced = readBytes(input);
            p256 = readBytes(input);
            x25519 = readBytes(input);
            if (input.read() != -1) throw new IOException("trailing request bytes");
        }
        if (challenge.length == 0 || challenge.length > 64 || maced.length == 0) {
            throw new IOException("invalid challenge or MacedPublicKey");
        }
        Class<?> binder = Class.forName("android.os.IBinder");
        Object service = Class.forName("android.os.ServiceManager")
                .getMethod("checkService", String.class).invoke(null, SERVICE + "/default");
        if (service == null) throw new IOException("RKP default service is unavailable");
        Class<?> api = Class.forName(SERVICE);
        Object proxy = Class.forName(SERVICE + "$Stub")
                .getMethod("asInterface", binder).invoke(null, service);
        Object info = api.getMethod("getHardwareInfo").invoke(proxy);
        int curve = info.getClass().getField("supportedEekCurve").getInt(info);

        byte[][] candidates;
        if (curve == 1) {
            candidates = new byte[][] {p256, x25519};
        } else if (curve == 2) {
            candidates = new byte[][] {x25519, p256};
        } else {
            // Some Qualcomm firmware reports an unsupported/unknown curve (0),
            // including the POCO F8 Pro. Try the available EEK chains rather than
            // failing before KeyMint has had an opportunity to accept one.
            candidates = new byte[][] {x25519, p256};
        }

        Class<?> keyClass = Class.forName(PREFIX + "MacedPublicKey");
        Object key = keyClass.getConstructor().newInstance();
        keyClass.getField("macedKey").set(key, maced);
        Object keys = Array.newInstance(keyClass, 1);
        Array.set(keys, 0, key);
        Class<?> deviceClass = Class.forName(PREFIX + "DeviceInfo");
        Class<?> protectedClass = Class.forName(PREFIX + "ProtectedData");

        Throwable lastFailure = null;
        for (byte[] eek : candidates) {
            if (eek == null || eek.length == 0) continue;
            Object device = deviceClass.getConstructor().newInstance();
            Object protectedData = protectedClass.getConstructor().newInstance();
            try {
                byte[] mac = (byte[]) api.getMethod("generateCertificateRequest",
                        boolean.class, keys.getClass(), byte[].class, byte[].class,
                        deviceClass, protectedClass).invoke(proxy, false, keys, eek, challenge,
                        device, protectedData);
                byte[] deviceBytes = (byte[]) deviceClass.getField("deviceInfo").get(device);
                byte[] protectedBytes = (byte[]) protectedClass.getField("protectedData").get(protectedData);
                if (mac == null || mac.length != 32) {
                    throw new IOException("invalid keysToSign MAC");
                }
                if (deviceBytes == null || deviceBytes.length == 0 || deviceBytes.length > LIMIT) {
                    throw new IOException("invalid DeviceInfo length");
                }
                if (protectedBytes == null || protectedBytes.length == 0 || protectedBytes.length > LIMIT) {
                    throw new IOException("invalid ProtectedData length");
                }
                java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
                try (DataOutputStream output = new DataOutputStream(buffer)) {
                    output.writeInt(0);
                    writeBytes(output, mac);
                    writeBytes(output, deviceBytes);
                    writeBytes(output, protectedBytes);
                }
                return buffer.toByteArray();
            } catch (InvocationTargetException failure) {
                Throwable cause = failure.getCause();
                lastFailure = cause == null ? failure : cause;
            } catch (Throwable failure) {
                lastFailure = failure;
            }
        }

        if (lastFailure instanceof ServiceSpecificException) {
            ServiceSpecificException exception = (ServiceSpecificException) lastFailure;
            throw exception;
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        throw new IOException("unsupported EEK curve: " + curve
                + "; no compatible EEK chain was supplied");
    }

    private static byte[] errorReply(int status, int code, String message) throws IOException {
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(status);
            if (status == 1) output.writeInt(code);
            if (message.length() > 1024) message = message.substring(0, 1024);
            writeBytes(output, message.getBytes(StandardCharsets.UTF_8));
        }
        return buffer.toByteArray();
    }

    private static byte[] readBytes(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > LIMIT) throw new IOException("invalid input length");
        byte[] bytes = new byte[length];
        input.readFully(bytes);
        return bytes;
    }

    private static void writeBytes(DataOutputStream output, byte[] bytes) throws IOException {
        if (bytes == null || bytes.length > LIMIT) throw new IOException("invalid output length");
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static final class ServiceSpecificException extends RuntimeException {
        ServiceSpecificException(String message) {
            super(message);
        }
    }
}
