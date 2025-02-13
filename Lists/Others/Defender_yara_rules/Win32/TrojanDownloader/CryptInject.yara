rule TrojanDownloader_Win32_CryptInject_BG_2147827779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CryptInject.BG!MTB"
        threat_id = "2147827779"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eastmedia3347.co.cc/d/dnl.php" ascii //weight: 1
        $x_1_2 = "httpb.exe" ascii //weight: 1
        $x_1_3 = "httpb run key" ascii //weight: 1
        $x_1_4 = "sremoveMe%i%i%i%i.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CryptInject_BH_2147827805_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CryptInject.BH!MTB"
        threat_id = "2147827805"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "down.21195.com/jmx.txt" ascii //weight: 1
        $x_1_2 = "zhegehaizhenbzda" ascii //weight: 1
        $x_1_3 = "CreateMutexA" ascii //weight: 1
        $x_1_4 = "UPX0" ascii //weight: 1
        $x_1_5 = "UPX1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

