import Foundation

public enum ByteFormatter: Sendable {
    public static func format(_ bytes: Int64) -> String {
        guard bytes > 0 else { return "0 B" }
        return ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    public static func splitFormat(_ bytes: Int64) -> (value: String, unit: String) {
        guard bytes > 0 else { return ("0", "B") }
        let formatted = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
        let parts = formatted.split(separator: " ", maxSplits: 1).map(String.init)
        if parts.count == 2 {
            return (parts[0], parts[1])
        }
        return (formatted, "")
    }
}
