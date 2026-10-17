using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.Serialization;

namespace Wachtl.Tray.Core
{
    [DataContract]
    public sealed class LivePing
    {
        [DataMember(Name = "target")] public string Target { get; set; } = string.Empty;
        [DataMember(Name = "up")] public bool Up { get; set; }
        [DataMember(Name = "rtt_ms")] public double? RttMs { get; set; }
        [DataMember(Name = "loss_pct")] public double LossPct { get; set; }
    }

    [DataContract]
    public sealed class LiveSpeedtest
    {
        [DataMember(Name = "down_mbps")] public double? DownMbps { get; set; }
        [DataMember(Name = "up_mbps")] public double? UpMbps { get; set; }
        [DataMember(Name = "ts")] public long Ts { get; set; }
    }

    /// <summary>Feld „internet“ von GET /tray/v1/status (ab 0.8.2; fehlt bei älteren Diensten und auf dem Server).</summary>
    [DataContract]
    public sealed class LiveInternet
    {
        [DataMember(Name = "pings")] public List<LivePing>? Pings { get; set; }
        [DataMember(Name = "rx_mbps")] public double? RxMbps { get; set; }
        [DataMember(Name = "tx_mbps")] public double? TxMbps { get; set; }
        [DataMember(Name = "speedtest")] public LiveSpeedtest? Speedtest { get; set; }
    }

    /// <summary>Zeilen oben im Menü: Ping ins Internet, aktuelle Datenrate, letzter Speedtest.</summary>
    public static class LiveTexts
    {
        public const int MaxLines = 5;
        private static readonly CultureInfo German = CultureInfo.GetCultureInfo("de-DE");

        /// <summary>Leere Liste = nichts anzeigen (Dienst zu alt oder nicht erreichbar).</summary>
        public static IList<string> Lines(LiveInternet? live, DateTime localNow)
        {
            var lines = new List<string>();
            if (live == null)
            {
                return lines;
            }

            var pings = live.Pings ?? new List<LivePing>();
            if (pings.Count == 0)
            {
                lines.Add("Ping Internet: keine Messung");
            }

            foreach (var p in pings)
            {
                if (lines.Count >= 3)
                {
                    break;
                }

                var text = "Ping " + p.Target + ": " + (p.Up && p.RttMs.HasValue ? Ms(p.RttMs.Value) : "keine Antwort");
                if (p.LossPct > 0)
                {
                    text += " · " + Number(p.LossPct) + " % Verlust";
                }

                lines.Add(text);
            }

            lines.Add(live.RxMbps.HasValue && live.TxMbps.HasValue
                ? "Jetzt: ↓ " + Mbps(live.RxMbps.Value) + "   ↑ " + Mbps(live.TxMbps.Value)
                : "Jetzt: Datenrate wird gemessen …");

            var st = live.Speedtest;
            if (st != null && (st.DownMbps.HasValue || st.UpMbps.HasValue))
            {
                var at = DateTimeOffset.FromUnixTimeSeconds(st.Ts).ToLocalTime().DateTime;
                var when = at.Date == localNow.Date ? at.ToString("HH:mm", German) : at.ToString("dd.MM. HH:mm", German);
                lines.Add("Speedtest " + when + ": ↓ " + (st.DownMbps.HasValue ? Mbps(st.DownMbps.Value) : "–")
                          + "   ↑ " + (st.UpMbps.HasValue ? Mbps(st.UpMbps.Value) : "–"));
            }
            else
            {
                lines.Add("Speedtest: noch keine Messung");
            }

            return lines;
        }

        public static string Ms(double ms) => (ms < 10 ? ms.ToString("0.0", German) : ms.ToString("0", German)) + " ms";

        public static string Mbps(double mbps) =>
            (mbps < 10 ? mbps.ToString("0.0", German) : mbps.ToString("0", German)) + " Mbit/s";

        private static string Number(double v) => v < 10 ? v.ToString("0.#", German) : v.ToString("0", German);
    }
}
