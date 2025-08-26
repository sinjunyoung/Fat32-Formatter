using Microsoft.Win32.SafeHandles;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace PickPack
{
    public static class Fat32Formatter
    {
        #region Const & Struct

        const uint FSCTL_LOCK_VOLUME = 0x00090018;
        const uint FSCTL_UNLOCK_VOLUME = 0x0009001c;
        const uint FSCTL_DISMOUNT_VOLUME = 0x00090020;
        const uint FILE_BEGIN = 0;
        const uint IOCTL_DISK_GET_LENGTH_INFO = 0x0007405c;


        [StructLayout(LayoutKind.Sequential)]
        private struct DISK_GEOMETRY
        {
            public ulong Cylinders;
            public uint MediaType;
            public uint TracksPerCylinder;
            public uint SectorsPerTrack;
            public uint BytesPerSector;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DISK_GEOMETRY_EX
        {
            public DISK_GEOMETRY Geometry;
            public ulong DiskSize;
            public byte Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DISK_LENGTH_INFO
        {
            public long Length;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct PARTITION_INFORMATION
        {
            public int PartitionType;
            public int BootIndicator;
            public long StartingOffset;
            public long PartitionLength;
            public uint HiddenSectors;
            public long PartitionNumber;
            public long Mbr;
        }

        // Structure to hold partition information
        [StructLayout(LayoutKind.Sequential)]
        public struct PARTITION_INFORMATION_EX
        {
            public int PartitionStyle;
            public long StartingOffset;
            public long PartitionLength;
            public int PartitionNumber;
            public byte IsRecognized;
            public Guid PartitionId;
            public Guid PartitionType;
            public long Mbr;
        }

        #endregion

        #region Dll Import

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string lpFileName, [MarshalAs(UnmanagedType.U4)] FileAccess dwDesiredAccess, [MarshalAs(UnmanagedType.U4)] FileShare dwShareMode, IntPtr lpSecurityAttributes, [MarshalAs(UnmanagedType.U4)] FileMode dwCreationDisposition, [MarshalAs(UnmanagedType.U4)] FileAttributes dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode, IntPtr lpInBuffer, int nInBufferSize, IntPtr lpOutBuffer, int nOutBufferSize, out int lpBytesReturned, IntPtr lpOverlapped);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile(SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFilePointerEx(SafeFileHandle hFile, long liDistanceToMove, out long lpNewFilePointer, uint dwMoveMethod);

        #endregion

        #region Private

        private static void DeviceIoControlOrThrow(SafeFileHandle hDevice, uint dwIoControlCode, IntPtr lpInBuffer, int nInBufferSize, IntPtr lpOutBuffer, int nOutBufferSize, out int lpBytesReturned)
        {
            if (!DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, out lpBytesReturned, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"DeviceIoControl 0x{dwIoControlCode:X8} failed");
            }
        }

        private static DISK_GEOMETRY_EX GetGeometry(SafeFileHandle hVol)
        {
            int size = Marshal.SizeOf<DISK_GEOMETRY_EX>();
            IntPtr pGeom = Marshal.AllocHGlobal(size);
            try
            {
                DeviceIoControlOrThrow(hVol, 0x00070000, IntPtr.Zero, 0, pGeom, size, out _);
                return Marshal.PtrToStructure<DISK_GEOMETRY_EX>(pGeom);
            }
            finally
            {
                Marshal.FreeHGlobal(pGeom);
            }
        }

        private static ulong GetDiskLength(SafeFileHandle hVol)
        {
            int size = Marshal.SizeOf<DISK_LENGTH_INFO>();
            IntPtr pInfo = Marshal.AllocHGlobal(size);
            try
            {
                DeviceIoControlOrThrow(hVol, IOCTL_DISK_GET_LENGTH_INFO, IntPtr.Zero, 0, pInfo, size, out _);
                return (ulong)Marshal.PtrToStructure<DISK_LENGTH_INFO>(pInfo).Length;
            }
            finally
            {
                Marshal.FreeHGlobal(pInfo);
            }
        }

        private static void SetFilePointer(SafeFileHandle hFile, long offset)
        {
            if (!SetFilePointerEx(hFile, offset, out _, FILE_BEGIN))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetFilePointerEx failed");
            }
        }

        private static void WriteData(SafeFileHandle hFile, byte[] data)
        {
            if (!WriteFile(hFile, data, (uint)data.Length, out uint bytesWritten, IntPtr.Zero) || bytesWritten != data.Length)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteFile failed");
            }
        }

        private static byte[] BuildFat32Vbr(uint bytesPerSector, uint spc, uint reservedSectors, uint numFats, uint fatSize, uint totalSectors, string? volumeLabel = null)
        {
            byte[] vbr = new byte[bytesPerSector];

            vbr[0x00] = 0xEB;
            vbr[0x01] = 0x58;
            vbr[0x02] = 0x90;

            Encoding.ASCII.GetBytes("MSWIN4.1").CopyTo(vbr, 0x03);

            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x0B), (ushort)bytesPerSector);
            vbr[0x0D] = (byte)spc;
            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x0E), (ushort)reservedSectors);
            vbr[0x10] = (byte)numFats;
            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x11), 0);
            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x13), 0);
            vbr[0x15] = 0xF8;
            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x16), 0);
            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x18), 0);
            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x1A), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(vbr.AsSpan(0x1C), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(vbr.AsSpan(0x20), totalSectors);

            BinaryPrimitives.WriteUInt32LittleEndian(vbr.AsSpan(0x24), fatSize);
            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x28), 0x0000);
            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x2A), 0x0000);
            BinaryPrimitives.WriteUInt32LittleEndian(vbr.AsSpan(0x2C), 2);
            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x30), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(vbr.AsSpan(0x32), 6);
            vbr[0x34] = 0;
            vbr[0x35] = 0x29;

            BinaryPrimitives.WriteUInt32LittleEndian(vbr.AsSpan(0x36), (uint)new Random().Next());

            string label = string.IsNullOrEmpty(volumeLabel) ? "NO NAME" : volumeLabel.ToUpperInvariant();
            label = label.PadRight(11).Substring(0, 11);
            Encoding.ASCII.GetBytes(label).CopyTo(vbr, 0x47);

            Encoding.ASCII.GetBytes("FAT32   ").CopyTo(vbr, 0x52);

            vbr[bytesPerSector - 2] = 0x55;
            vbr[bytesPerSector - 1] = 0xAA;

            return vbr;
        }

        private static byte[] BuildFsInfo(uint bytesPerSector, uint freeClusters, uint nextFreeCluster)
        {
            byte[] fsInfo = new byte[bytesPerSector];

            BinaryPrimitives.WriteUInt32LittleEndian(fsInfo.AsSpan(0x00), 0x41615252);
            BinaryPrimitives.WriteUInt32LittleEndian(fsInfo.AsSpan(0x1E4), 0x61417272);
            BinaryPrimitives.WriteUInt32LittleEndian(fsInfo.AsSpan(0x1E8), freeClusters);
            BinaryPrimitives.WriteUInt32LittleEndian(fsInfo.AsSpan(0x1EC), nextFreeCluster);
            BinaryPrimitives.WriteUInt32LittleEndian(fsInfo.AsSpan(0x1FC), 0xAA550000);

            return fsInfo;
        }

        private static void WriteFat32Entry(byte[] sector, uint index, uint value)
        {
            int offset = (int)(index * 4);
            BinaryPrimitives.WriteUInt32LittleEndian(sector.AsSpan(offset), value & 0x0FFFFFFF);
        }

        private static void WriteZeroData(SafeFileHandle hFile, uint bytesPerSector, ulong startLba, uint numSectors)
        {
            int bufferSize = (int)Math.Min((long)bytesPerSector * numSectors, 8 * 1024 * 1024);
            byte[] buffer = new byte[bufferSize];

            ulong sectorsWritten = 0;
            while (sectorsWritten < numSectors)
            {
                long sectorsToWriteInThisPass = (long)Math.Min(numSectors - sectorsWritten, (ulong)bufferSize / bytesPerSector);
                long bytesToWrite = sectorsToWriteInThisPass * bytesPerSector;

                SetFilePointer(hFile, (long)((startLba + sectorsWritten) * bytesPerSector));
                WriteData(hFile, buffer);

                sectorsWritten += (ulong)sectorsToWriteInThisPass;
            }
        }

        private static void WriteVolumeLabel(SafeFileHandle hVol, uint bytesPerSector, ulong firstDataSector, string label)
        {
            byte[] sector = new byte[bytesPerSector];

            string volLabel = label.ToUpperInvariant().PadRight(11).Substring(0, 11);
            Encoding.ASCII.GetBytes(volLabel).CopyTo(sector, 0);

            sector[11] = 0x08;

            for (int i = 12; i < sector.Length; i++)
                sector[i] = 0;

            SetFilePointer(hVol, (long)(firstDataSector * bytesPerSector));
            WriteData(hVol, sector);
        }

        #endregion

        public static void FormatVolume(SafeFileHandle hVol, string? volumeLabel = null)
        {
            if (hVol == null || hVol.IsInvalid)
            {
                throw new ArgumentException("유효하지 않은 디스크 핸들입니다.", nameof(hVol));
            }

            DISK_GEOMETRY_EX geom = GetGeometry(hVol);
            uint bytesPerSector = (uint)geom.Geometry.BytesPerSector;
            ulong length = GetDiskLength(hVol);
            ulong totalSectors = length / bytesPerSector;

            uint spc = 0;
            ulong totalBytes = totalSectors * bytesPerSector;
            if (totalBytes <= 16 * 1024 * 1024) spc = 1;       // 512B
            else if (totalBytes <= 32 * 1024 * 1024) spc = 2;  // 1KB
            else if (totalBytes <= 64 * 1024 * 1024) spc = 4;  // 2KB
            else if (totalBytes <= 128 * 1024 * 1024) spc = 8; // 4KB
            else if (totalBytes <= 260 * 1024 * 1024) spc = 16;// 8KB
            else if (totalBytes <= 8UL * 1024 * 1024 * 1024) spc = 32;  // 16KB
            else if (totalBytes <= 16UL * 1024 * 1024 * 1024) spc = 64; // 32KB
            else spc = 128; //  64KB

            uint reservedSectors = 32;
            uint numFats = 2;

            uint dataSectors = (uint)(totalSectors - (reservedSectors + (numFats * 1)));
            uint totalClusters = dataSectors / spc;
            uint fatSize = (uint)((totalClusters * 4 + bytesPerSector - 1) / bytesPerSector);

            byte[] vbr = BuildFat32Vbr(bytesPerSector, spc, reservedSectors, numFats, fatSize, (uint)totalSectors, volumeLabel);
            byte[] fsInfo = BuildFsInfo(bytesPerSector, totalClusters - 1, 3);

            void WriteSectors(ulong lba, ReadOnlySpan<byte> data)
            {
                SetFilePointer(hVol, (long)(lba * bytesPerSector));
                WriteData(hVol, data.ToArray());
            }

            WriteSectors(0, vbr);
            WriteSectors(1, fsInfo);

            if (6 > 0)
            {
                WriteSectors(6, vbr);
                WriteSectors(7, fsInfo);
            }

            ulong fat1Lba = reservedSectors;
            ulong fat2Lba = reservedSectors + fatSize;
            byte[] firstFatSector = new byte[bytesPerSector];

            WriteFat32Entry(firstFatSector, 0, 0x0FFFFFF8);
            WriteFat32Entry(firstFatSector, 1, 0xFFFFFFFF);
            WriteFat32Entry(firstFatSector, 2, 0x0FFFFFFF);

            WriteSectors(fat1Lba, firstFatSector);
            WriteZeroData(hVol, bytesPerSector, fat1Lba + 1, fatSize - 1);
            WriteSectors(fat2Lba, firstFatSector);
            WriteZeroData(hVol, bytesPerSector, fat2Lba + 1, fatSize - 1);

            ulong firstDataSector = reservedSectors + (ulong)numFats * fatSize;
            ulong rootDataLba = firstDataSector + (ulong)(2 - 2) * spc;
            WriteZeroData(hVol, bytesPerSector, rootDataLba, spc);

            if (!string.IsNullOrEmpty(volumeLabel))
                WriteVolumeLabel(hVol, bytesPerSector, firstDataSector, volumeLabel ?? "NO NAME");
        }

        public static void Format(char driveLetter, string? volumeLabel = null)
        {
            string volPath = $@"\\.\{char.ToUpperInvariant(driveLetter)}:";

            using SafeFileHandle hVol = CreateFile(volPath,
                FileAccess.ReadWrite,
                FileShare.ReadWrite,
                IntPtr.Zero,
                FileMode.Open,
                FileAttributes.Normal,
                IntPtr.Zero);

            if (hVol.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to open {volPath}");

            try
            {
                DeviceIoControlOrThrow(hVol, FSCTL_LOCK_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out _);
                DeviceIoControlOrThrow(hVol, FSCTL_DISMOUNT_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out _);

                FormatVolume(hVol, volumeLabel);
            }
            finally
            {
                DeviceIoControlOrThrow(hVol, FSCTL_UNLOCK_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out _);
            }
        }
    }
}
