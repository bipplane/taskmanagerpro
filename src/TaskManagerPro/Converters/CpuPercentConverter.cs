using System.Globalization;
using System.Windows.Data;

namespace TaskManagerPro.Converters;

public class CpuPercentConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is double cpu)
            return $"{cpu:F1}%";
        return "0.0%";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
