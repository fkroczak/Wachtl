using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Wachtl.Tray.Core
{
    /// <summary>
    /// Kleiner JSON-Leser/-Schreiber für die paar Felder der lokalen Schnittstelle – keine NuGet-Abhängigkeit in der .exe.
    /// Objekte werden zu Dictionary&lt;string, object?&gt;, Arrays zu List&lt;object?&gt;, Zahlen zu double.
    /// </summary>
    public static class TrayJson
    {
        public static object? Parse(string text)
        {
            if (text == null)
            {
                throw new FormatException("Kein JSON.");
            }

            var reader = new Reader(text);
            reader.SkipWhitespace();
            var value = reader.ReadValue(0);
            reader.SkipWhitespace();
            if (!reader.AtEnd)
            {
                throw new FormatException("Zusätzliche Zeichen nach dem JSON-Wert.");
            }

            return value;
        }

        /// <summary>Parst ein Objekt; null, wenn der Text kein JSON-Objekt ist.</summary>
        public static Dictionary<string, object?>? TryParseObject(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return null;
            }

            try
            {
                return Parse(text!) as Dictionary<string, object?>;
            }
            catch (FormatException)
            {
                return null;
            }
        }

        public static string GetString(Dictionary<string, object?> obj, string name, string fallback = "") =>
            obj.TryGetValue(name, out var v) && v is string s ? s : fallback;

        public static bool GetBool(Dictionary<string, object?> obj, string name, bool fallback = false) =>
            obj.TryGetValue(name, out var v) && v is bool b ? b : fallback;

        public static long GetLong(Dictionary<string, object?> obj, string name, long fallback = 0) =>
            obj.TryGetValue(name, out var v) && v is double d && !double.IsNaN(d) && Math.Abs(d) < 9e15 ? (long)d : fallback;

        public static string Quote(string? value)
        {
            if (value == null)
            {
                return "null";
            }

            var sb = new StringBuilder(value.Length + 2);
            sb.Append('"');
            foreach (var c in value)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < 0x20 || c == ' ' || c == ' ')
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.Append(c);
                        }

                        break;
                }
            }

            sb.Append('"');
            return sb.ToString();
        }

        private sealed class Reader
        {
            private const int MaxDepth = 32;
            private readonly string _s;
            private int _i;

            public Reader(string s)
            {
                _s = s;
            }

            public bool AtEnd => _i >= _s.Length;

            public void SkipWhitespace()
            {
                while (_i < _s.Length && (_s[_i] == ' ' || _s[_i] == '\t' || _s[_i] == '\n' || _s[_i] == '\r'))
                {
                    _i++;
                }
            }

            public object? ReadValue(int depth)
            {
                if (depth > MaxDepth)
                {
                    throw new FormatException("JSON zu tief verschachtelt.");
                }

                if (AtEnd)
                {
                    throw new FormatException("Unerwartetes Ende.");
                }

                var c = _s[_i];
                switch (c)
                {
                    case '{': return ReadObject(depth);
                    case '[': return ReadArray(depth);
                    case '"': return ReadString();
                    case 't': Expect("true"); return true;
                    case 'f': Expect("false"); return false;
                    case 'n': Expect("null"); return null;
                    default:
                        if (c == '-' || (c >= '0' && c <= '9'))
                        {
                            return ReadNumber();
                        }

                        throw new FormatException("Unerwartetes Zeichen '" + c + "'.");
                }
            }

            private void Expect(string word)
            {
                if (string.CompareOrdinal(_s, _i, word, 0, word.Length) != 0)
                {
                    throw new FormatException("Ungültiges Literal.");
                }

                _i += word.Length;
            }

            private Dictionary<string, object?> ReadObject(int depth)
            {
                var result = new Dictionary<string, object?>(StringComparer.Ordinal);
                _i++;
                SkipWhitespace();
                if (!AtEnd && _s[_i] == '}')
                {
                    _i++;
                    return result;
                }

                while (true)
                {
                    SkipWhitespace();
                    if (AtEnd || _s[_i] != '"')
                    {
                        throw new FormatException("Schlüssel erwartet.");
                    }

                    var key = ReadString();
                    SkipWhitespace();
                    if (AtEnd || _s[_i] != ':')
                    {
                        throw new FormatException("':' erwartet.");
                    }

                    _i++;
                    SkipWhitespace();
                    result[key] = ReadValue(depth + 1);
                    SkipWhitespace();
                    if (AtEnd)
                    {
                        throw new FormatException("Unerwartetes Ende im Objekt.");
                    }

                    if (_s[_i] == ',')
                    {
                        _i++;
                        continue;
                    }

                    if (_s[_i] == '}')
                    {
                        _i++;
                        return result;
                    }

                    throw new FormatException("',' oder '}' erwartet.");
                }
            }

            private List<object?> ReadArray(int depth)
            {
                var result = new List<object?>();
                _i++;
                SkipWhitespace();
                if (!AtEnd && _s[_i] == ']')
                {
                    _i++;
                    return result;
                }

                while (true)
                {
                    SkipWhitespace();
                    result.Add(ReadValue(depth + 1));
                    SkipWhitespace();
                    if (AtEnd)
                    {
                        throw new FormatException("Unerwartetes Ende im Array.");
                    }

                    if (_s[_i] == ',')
                    {
                        _i++;
                        continue;
                    }

                    if (_s[_i] == ']')
                    {
                        _i++;
                        return result;
                    }

                    throw new FormatException("',' oder ']' erwartet.");
                }
            }

            private string ReadString()
            {
                _i++;
                var sb = new StringBuilder();
                while (true)
                {
                    if (AtEnd)
                    {
                        throw new FormatException("Unbeendete Zeichenkette.");
                    }

                    var c = _s[_i++];
                    if (c == '"')
                    {
                        return sb.ToString();
                    }

                    if (c != '\\')
                    {
                        sb.Append(c);
                        continue;
                    }

                    if (AtEnd)
                    {
                        throw new FormatException("Unbeendete Escape-Sequenz.");
                    }

                    var e = _s[_i++];
                    switch (e)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            if (_i + 4 > _s.Length
                                || !int.TryParse(_s.Substring(_i, 4), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var code))
                            {
                                throw new FormatException("Ungültige \\u-Sequenz.");
                            }

                            sb.Append((char)code);
                            _i += 4;
                            break;
                        default:
                            throw new FormatException("Ungültige Escape-Sequenz.");
                    }
                }
            }

            private double ReadNumber()
            {
                var start = _i;
                while (_i < _s.Length && "+-0123456789.eE".IndexOf(_s[_i]) >= 0)
                {
                    _i++;
                }

                if (!double.TryParse(_s.Substring(start, _i - start), NumberStyles.Float, CultureInfo.InvariantCulture, out var d))
                {
                    throw new FormatException("Ungültige Zahl.");
                }

                return d;
            }
        }
    }
}
