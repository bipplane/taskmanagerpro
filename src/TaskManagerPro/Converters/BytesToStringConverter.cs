using System.Globalization;
using System.Windows.Data;

namespace TaskManagerPro.Converters;

public class BytesToStringConverter : IValueConverter
{
    private static readonly string[] Suffixes = ["B", "KB", "MB", "GB", "TB"];

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not long bytes) return "0 B";
        if (bytes == 0) return "0 B";

        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < Suffixes.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:F1} {Suffixes[order]}";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
