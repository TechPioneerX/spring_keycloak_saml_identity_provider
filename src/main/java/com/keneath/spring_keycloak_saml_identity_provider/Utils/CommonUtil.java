package com.keneath.spring_keycloak_saml_identity_provider.Utils;


import javax.servlet.http.HttpServletRequest;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

public class CommonUtil {

    public static String uuidGenerator() {
        return UUID.randomUUID().toString();
    }

    private static final String[] IP_HEADERS = {
            "X-Forwarded-For",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",
            "REMOTE_ADDR"
    };

    public static Date addDaysToDate(Date date, int days) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.DATE, days); //minus number would decrement the days
        return cal.getTime();
    }

    public static Date calculateExpiryDate(Integer expiryTimeInMinutes) {
        Calendar cal = Calendar.getInstance();
        cal.getTime();
        cal.add(Calendar.MINUTE, expiryTimeInMinutes);
        return cal.getTime();
    }

    public static Date convertStringToDateTime(String dateTime) throws ParseException {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormat.parse(dateTime);
    }

    public static String convertTimeByTimezone(String fromTime, String fromTimeZone, String toTimeZone) {

        // Create a LocalTime object from the original time
        LocalTime localTime = LocalTime.parse(fromTime, DateTimeFormatter.ofPattern("HH:mm:ss"));

        // Create ZonedDateTime with original time and fromTimeZone
        ZonedDateTime fromDateTime = ZonedDateTime.of(localTime.atDate(LocalDate.now()), ZoneId.of(fromTimeZone));

        // Convert from fromTimeZone to toTimeZone
        ZonedDateTime toDateTime = fromDateTime.withZoneSameInstant(ZoneId.of(toTimeZone));

        // Extract the LocalTime from the converted ZonedDateTime
        LocalTime toTime = toDateTime.toLocalTime();

        // Format the converted time in the desired format

        return toTime.format(DateTimeFormatter.ofPattern("HH:mm:ss"));
    }

    public static String removeStripeCode(String errorMessage){
        int requestIdIndex = errorMessage.indexOf("; request-id:");
        if (requestIdIndex != -1) {
            errorMessage = errorMessage.substring(0, requestIdIndex);
            requestIdIndex = errorMessage.indexOf("; code:");
            if (requestIdIndex != -1) {
                return errorMessage.substring(0, requestIdIndex);
            }
        }
        return errorMessage;
    }

    public static Double convertTwoDecimal(Double originalValue){
        // Create a DecimalFormat object with the desired format pattern
        DecimalFormat decimalFormat = new DecimalFormat("#0.00");

        // Apply the format to the original value
        return Double.parseDouble(decimalFormat.format(originalValue));
    }

    public static String getTimeStamp(){
        long timestamp = System.currentTimeMillis() / 1000;

        // Convert the timestamp to a string
        return Long.toString(timestamp);
    }

    public static String getRequestIP(HttpServletRequest request) {
        for (String header: IP_HEADERS){
            String value = request.getHeader(header);
            if (value == null || value.isEmpty() || "127.0.0.1".equals(value) || "unknown".equalsIgnoreCase(value)) {
                continue;
            }
            System.out.println("header IP address: " + header + ": " + value);
            String[] parts = value.split("\\s*,\\s*");
            return parts[0];
        }
        System.out.println("header IP address: from request.getRemoteAddr() : " + request.getRemoteAddr());
        return request.getRemoteAddr();
    }

    public static Date getForeverDate(){
        String dateString = "01/01/2099";
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy");

        LocalDate localDate = LocalDate.parse(dateString, formatter);
        LocalDateTime localDateTime = localDate.atStartOfDay();
        return Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
    }

    public static Date getFurtherOneWeekDate(){
        return Date.from((LocalDate.now().plusWeeks(1)).atStartOfDay(ZoneId.systemDefault()).toInstant());
    }

    public static String convertUtcDateObjectToZonedDateString(Date utcDate, String timeZone){

        if( utcDate == null )
            utcDate = new Date();
        if( timeZone == null )
            timeZone = "America/New_York";

        // Create a SimpleDateFormat object with the desired format
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yy HH:mm:ss");

        // Set the time zone of the SimpleDateFormat object
        sdf.setTimeZone(TimeZone.getTimeZone(timeZone));

        // Format the date in the specified time zone
        return sdf.format(utcDate);
    }

    public static String[] extractFirstAndLastName( String fullName ){
        String[] words = fullName.split("\\s+");
        String firstName = words[0];
        StringBuilder lastName = new StringBuilder();
        for( int i = 1; i < words.length; i++ ){
            if( lastName.length() > 0 )
                lastName.append(" ").append(words[i]);
            else
                lastName = new StringBuilder(words[i]);
        }

        return new String[]{firstName, String.valueOf(lastName)};
    }

    public static String inflate(byte[] deflatedData, boolean useWrap) throws Exception {
        try {
            byte[] inflatedData = new byte[(10 * deflatedData.length)];
            Inflater decompresser = new Inflater(useWrap);
            decompresser.setInput(deflatedData, 0, deflatedData.length);
            int inflatedBytesLength = decompresser.inflate(inflatedData);
            decompresser.end();
            return new String(inflatedData, 0, inflatedBytesLength);
        }
        catch(DataFormatException dfe) {
            throw new Exception(dfe);
        }
    }
}
