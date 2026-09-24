import Foundation

public enum ByteFormatter {
    private static let formatter: ByteCountFormatter = {
        let bcf = ByteCountFormatter()
        bcf.countStyle = .file
        bcf.allowedUnits = [.useAll]
        bcf.includesUnit = true
        bcf.isAdaptive = true
        return bcf
    }()

    private static let valueFormatter: ByteCountFormatter = {
        let bcf = ByteCountFormatter()
        bcf.countStyle = .file
        bcf.allowedUnits = [.useAll]
        bcf.includesUnit = false
        bcf.isAdaptive = true
        return bcf
    }()

    private static let unitFormatter: ByteCountFormatter = {
        let bcf = ByteCountFormatter()
        bcf.countStyle = .file
        bcf.allowedUnits = [.useAll]
        bcf.includesUnit = true
        bcf.includesCount = false
        bcf.isAdaptive = true
        return bcf
    }()

    public static func format(_ bytes: Int64) -> String {
        guard bytes > 0 else { return "0 B" }
        return formatter.string(fromByteCount: bytes)
    }

    public static func splitFormat(_ bytes: Int64) -> (value: String, unit: String) {
        guard bytes > 0 else { return ("0", "B") }
        let val = valueFormatter.string(fromByteCount: bytes).trimmingCharacters(in: .whitespaces)
        let unit = unitFormatter.string(fromByteCount: bytes).trimmingCharacters(in: .whitespaces)
        return (val, unit)
    }
}
