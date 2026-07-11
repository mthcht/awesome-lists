rule Trojan_Win64_DiskWriter_SP_2147837091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiskWriter.SP!MTB"
        threat_id = "2147837091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 54 24 30 48 8d 0d ?? ?? ?? ?? 89 54 24 28 45 33 c9 ba 00 00 00 10 c7 44 24 20 03 00 00 00 45 8d 41 03 ff 15 ?? ?? ?? ?? 4c 8d 4c 24 40 48 c7 44 24 20 00 00 00 00 48 8b c8 48 8d 54 24 50 41 b8 00 02 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = "MBR-MALWARE-EXAMPLES.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DiskWriter_AHB_2147959012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiskWriter.AHB!MTB"
        threat_id = "2147959012"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Horrible choise!" ascii //weight: 50
        $x_40_2 = "You are about to run Hydrazine" ascii //weight: 40
        $x_30_3 = "The destruction is unrecoverable!" ascii //weight: 30
        $x_20_4 = "I am not responsible" ascii //weight: 20
        $x_10_5 = "be aware for all cost of this malware" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DiskWriter_KK_2147970712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiskWriter.KK!MTB"
        threat_id = "2147970712"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {49 8b c8 49 8b c0 83 e1 0f 83 e0 1f 41 0f b6 14 0b 41 32 14 02 41 32 14 30 41 88 14 38 49 ff c0 49 81 f8 00 c8 00 00}  //weight: 20, accuracy: High
        $x_10_2 = "PETYA RANSOMWARE" ascii //weight: 10
        $x_5_3 = "C:\\YOUR_KEY.txt" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DiskWriter_AHA_2147971380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiskWriter.AHA!MTB"
        threat_id = "2147971380"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "rundll32.exe syssetup.dll,SetupInfObjectInstallAction" ascii //weight: 30
        $x_20_2 = "/k dism /image:e:\\ /remove-driver /driver:oem1.inf" ascii //weight: 20
        $x_10_3 = "cmd.exe /c \"takeown /f \"C:\\Windows\\System32\" /r /d y && icacls \"C:\\Windows\\System32\" /grant Everyone:F /t && attrib -r -s -h" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DiskWriter_MK_2147973386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiskWriter.MK!MTB"
        threat_id = "2147973386"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MBR berhasil ditulis!" ascii //weight: 10
        $x_5_2 = "Gagal membuka handle drive. Pastikan Anda sudah Administrator." ascii //weight: 5
        $x_3_3 = "Gagal menulis ke MBR. Error: %lu" ascii //weight: 3
        $x_2_4 = "\\\\.\\PhysicalDrive0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

