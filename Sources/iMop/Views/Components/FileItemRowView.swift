import iMopCore
import SwiftUI
import AppKit

public struct FileItemRowView: View {
    public let item: JunkItem
    public let onToggle: () -> Void
    public let onExclude: () -> Void

    @LocalState private var isHovered: Bool = false

    public init(item: JunkItem, onToggle: @escaping () -> Void, onExclude: @escaping () -> Void) {
        self.item = item
        self.onToggle = onToggle
        self.onExclude = onExclude
    }

    private var fileIcon: Image {
        if FileManager.default.fileExists(atPath: item.path.path) {
            let nsImage = NSWorkspace.shared.icon(forFile: item.path.path)
            return Image(nsImage: nsImage)
        } else {
            return Image(systemName: "doc")
        }
    }

    private static let dateFormatter: DateFormatter = {
        let df = DateFormatter()
        df.dateStyle = .medium
        df.timeStyle = .short
        return df
    }()

    public var body: some View {
        HStack(spacing: 12) {
            // Checkbox
            Button(action: onToggle) {
                Image(systemName: item.isSelected ? "checkmark.square.fill" : "square")
                    .font(.system(size: 16))
                    .foregroundStyle(item.isSelected ? Color.blue : Color.secondary.opacity(0.4))
            }
            .buttonStyle(.plain)

            // File Icon
            fileIcon
                .resizable()
                .scaledToFit()
                .frame(width: 28, height: 28)

            // File Info
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(item.name)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(.primary)
                        .lineLimit(1)

                    if let hint = item.detailHint {
                        Text(hint)
                            .font(.system(size: 10, weight: .medium))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.secondary.opacity(0.12))
                            .clipShape(Capsule())
                            .foregroundStyle(.secondary)
                    }
                }

                Text(item.path.path)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer()

            // Date & Size
            VStack(alignment: .trailing, spacing: 3) {
                Text(ByteFormatter.format(item.size))
                    .font(.system(size: 13, weight: .semibold, design: .rounded))
                    .foregroundStyle(.primary)

                Text(Self.dateFormatter.string(from: item.lastModified))
                    .font(.system(size: 10))
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(isHovered ? Color.primary.opacity(0.04) : Color.clear)
        )
        .onHover { hovering in
            isHovered = hovering
        }
        .contextMenu {
            Button {
                NSWorkspace.shared.activateFileViewerSelecting([item.path])
            } label: {
                Label("Reveal in Finder", systemImage: "folder")
            }

            Button {
                NSWorkspace.shared.open(item.path)
            } label: {
                Label("Open Item", systemImage: "arrow.up.right.square")
            }

            Divider()

            Button(role: .destructive, action: onExclude) {
                Label("Exclude from Future Scans", systemImage: "nosign")
            }
        }
    }
}
