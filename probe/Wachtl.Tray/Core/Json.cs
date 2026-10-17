using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace Wachtl.Tray.Core
{
    /// <summary>Körper von POST /tray/v1/report.</summary>
    [DataContract]
    public sealed class ReportRequest
    {
        [DataMember(Name = "occurred_at", Order = 0)] public long OccurredAt { get; set; }
        [DataMember(Name = "category", Order = 1)] public string Category { get; set; } = string.Empty;
        [DataMember(Name = "duration", Order = 2)] public string Duration { get; set; } = string.Empty;
        [DataMember(Name = "description", Order = 3)] public string Description { get; set; } = string.Empty;
        [DataMember(Name = "user", Order = 4)] public string User { get; set; } = string.Empty;
    }

    /// <summary>Antwort von POST /tray/v1/report: {"ok", "delivered"} oder {"error"}.</summary>
    [DataContract]
    public sealed class ReportResponse
    {
        [DataMember(Name = "ok")] public bool Ok { get; set; }
        [DataMember(Name = "delivered")] public bool Delivered { get; set; }
        [DataMember(Name = "error")] public string? Error { get; set; }
    }

    /// <summary>DataContractJsonSerializer aus dem Framework – keine zusätzliche DLL neben der .exe.</summary>
    public static class Json
    {
        public static string Write<T>(T value)
        {
            using (var stream = new MemoryStream())
            {
                new DataContractJsonSerializer(typeof(T)).WriteObject(stream, value);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }

        /// <summary>null bei leerem oder ungültigem JSON.</summary>
        public static T? Read<T>(string? json)
            where T : class
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }

            try
            {
                using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    return new DataContractJsonSerializer(typeof(T)).ReadObject(stream) as T;
                }
            }
            catch (SerializationException)
            {
                return null;
            }
        }
    }
}
