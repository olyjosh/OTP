import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by olyjosh on 10/05/2017.
 */
public class OTP {

    public final static int TIME_IN_MILLI_SECONDS = 1;
    public final static int TIME_IN_SECONDS = 1000;
    public final static int TIME_IN_MINUTES = 60 * 1000;
    public final static int TIME_IN_HOURS = 60 * 60 * 1000;
    public final static int TIME_IN_DAYS = 24 * 60 * 60 * 1000;

    // using this method to calculate power to be use in computing modulus is faster than using Math.pow, however not that significant
    private static final int[] DIGITS_POWER
            // 0   1   2     3     4       5       6        7           8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};


    /**
     * @param secretKey is the key you use in generating others.OTP. Keep this secret and secure as possible.
     *                  You are advised to encrypt your secretKey and to even load it in ram while you use this for a short period of time
     * @param timeStamp is the time you want others.OTP to be generated for you. You are expected to use System.currentTimeMillis() to get system time.
     * @param t0 is the time in the past you are considering.
     * @param timeRange is the range of time the others.OTP is meant to be valid for. This is the same as expiry
     * @param time_in is the type of time you are computing others.OTP for. to specify others.OTP timeRange(validity) that last for seconds, minutes, hours, etc
     * @param codeDigits is the number of charaters that you want others.OTP to be
     * @return will return String of others.OTP
     */
    public String tOTP(String secretKey,long timeStamp, long t0,int timeRange,int time_in, int codeDigits)
            throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException{
        long T = ((timeStamp - t0)/time_in) / timeRange;
        final SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA1");
        final Mac hmac = Mac.getInstance("HmacSHA1");
        hmac.init(secretKeySpec);
        hmac.update(Long.toHexString(T).getBytes());
        return truncate(hmac.doFinal(), codeDigits);
    }


    private String truncate(byte[] hash, int codeDigits){
         String result = null;
         int offset = hash[hash.length - 1] & 0xf;

         int binary =
                 ((hash[offset] & 0x7f) << 24) |
                         ((hash[offset + 1] & 0xff) << 16) |
                         ((hash[offset + 2] & 0xff) << 8) |
                         (hash[offset + 3] & 0xff);

         int otp = binary % DIGITS_POWER[codeDigits];

         result = Integer.toString(otp);
         while (result.length() < codeDigits) {
             result = "0" + result;
         }

         return result;
     }

}
