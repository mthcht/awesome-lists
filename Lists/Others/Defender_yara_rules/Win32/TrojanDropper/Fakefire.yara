rule TrojanDropper_Win32_Fakefire_B_2147601826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Fakefire.B"
        threat_id = "2147601826"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakefire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MacInstaller" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\pjtAwsVariantioner.vbp" wide //weight: 1
        $x_1_3 = "MSFirewall" wide //weight: 1
        $x_1_4 = "C:\\VBVirus\\FuckYou.ptt" wide //weight: 1
        $x_1_5 = "\\Set1.Ico" wide //weight: 1
        $x_1_6 = "\\BProtect.exe" wide //weight: 1
        $x_1_7 = "wscript.Shell" wide //weight: 1
        $x_1_8 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_9 = {8b c4 8b 4d ac 89 08 8b 55 b0 89 50 04 8b 4d b4 89 48 08 8b 55 b8 89 50 0c 68 ?? ?? 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 8b d0 8d 4d cc ff 15 ?? ?? 40 00 8b d0 8b 4d 08 83 c1 40 ff 15 ?? ?? 40 00 8d 4d cc ff 15 ?? ?? 40 00 c7 45 fc 05 00 00 00 6a 00 68 ?? ?? 40 00 8d 45 bc 50 ff 15 ?? ?? 40 00 8d 4d bc 51 8d 55 d0 52 ff 15 ?? ?? 40 00 c7 45 fc 06 00 00 00 68 ?? ?? 40 00 8b 45 08 8b 48 38 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

