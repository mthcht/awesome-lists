rule Trojan_Win32_Omaneat_MR_2147780047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Omaneat.MR"
        threat_id = "2147780047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Omaneat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fbhrlhum" ascii //weight: 1
        $x_1_2 = "\\TEMP\\5urpd3p4o" ascii //weight: 1
        $x_1_3 = "C:\\TEMP\\nso28C8.tmp\\nsis7z.dll" ascii //weight: 1
        $x_1_4 = "Beam Wallet" ascii //weight: 1
        $x_1_5 = "REPARSE_POINT" ascii //weight: 1
        $x_1_6 = "\\ExecCmd.dll" ascii //weight: 1
        $x_1_7 = "SPARSE_FILE|" ascii //weight: 1
        $x_1_8 = "\\WndSubclass.dll" ascii //weight: 1
        $x_1_9 = "RichEdit" ascii //weight: 1
        $x_1_10 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_11 = "RegDeleteKeyExA" ascii //weight: 1
        $x_1_12 = "SysListView32" ascii //weight: 1
        $x_1_13 = "CryptDeriveKey" ascii //weight: 1
        $x_1_14 = "CryptEncrypt" ascii //weight: 1
        $x_1_15 = "CryptDestroyKey" ascii //weight: 1
        $x_1_16 = "CryptReleaseContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Omaneat_MS_2147780850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Omaneat.MS!MTB"
        threat_id = "2147780850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Omaneat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_2 = "\\Wallets" ascii //weight: 1
        $x_1_3 = "DRIVE_REMOVABLE" ascii //weight: 1
        $x_1_4 = "LOCALAPPDATA" ascii //weight: 1
        $x_1_5 = "files\\information.txt" ascii //weight: 1
        $x_1_6 = "\\vcruntime140.dll" ascii //weight: 1
        $x_1_7 = "softokn3.dll" ascii //weight: 1
        $x_1_8 = "MetaMask" ascii //weight: 1
        $x_1_9 = "\\Local Extension Settings" ascii //weight: 1
        $x_1_10 = "CreateDirectoryA" ascii //weight: 1
        $x_1_11 = "DeleteFileW" ascii //weight: 1
        $x_1_12 = "FindFirstFileW" ascii //weight: 1
        $x_1_13 = "FindNextFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

