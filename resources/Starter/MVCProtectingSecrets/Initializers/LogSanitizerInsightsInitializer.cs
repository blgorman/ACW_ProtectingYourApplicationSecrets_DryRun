using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using System.Text.RegularExpressions;

namespace MVCProtectingSecrets.Initializers
{
    public class LogSanitizerInsightsInitializer : ITelemetryInitializer
    {
        public void Initialize(ITelemetry telemetry)
        {
            var traceTelemetry = telemetry as TraceTelemetry;

            if (traceTelemetry != null)
            {
                traceTelemetry.Message = SanitizeString(traceTelemetry.Message);
                // If we don't remove this CustomDimension, the telemetry message will still contain the PII in the "OriginalFormat" property.
                traceTelemetry.Properties.Remove("OriginalFormat");
            }
        }

        public static string SanitizeString(string msg)
        {
            // Sanitize email addresses
            msg = SanitizeEmail(msg);

            //return sanitized string
            return msg;
        }

        private static string SanitizeEmail(string msg)
        {
            var regexEmail = @"\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*";
            var replacedEmail = "[emailaddress]";
            return Regex.Replace(msg, regexEmail, replacedEmail);
        }
    }
}
