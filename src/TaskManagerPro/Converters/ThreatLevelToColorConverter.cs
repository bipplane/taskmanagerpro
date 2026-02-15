using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using TaskManagerPro.Core.Enums;

namespace TaskManagerPro.Converters;

public class ThreatLevelToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not ThreatLevel level) return Brushes.Transparent;

        return level switch
        {
            ThreatLevel.None => Brushes.Transparent,
            ThreatLevel.Info => new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)),
            ThreatLevel.Low => new SolidColorBrush(Color.FromRgb(0xEA, 0xB3, 0x08)),
            ThreatLevel.Medium => new SolidColorBrush(Color.FromRgb(0xF9, 0x73, 0x16)),
            ThreatLevel.High => new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44)),
            ThreatLevel.Critical => new SolidColorBrush(Color.FromRgb(0x93, 0x33, 0xEA)),
            _ => Brushes.Transparent
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
