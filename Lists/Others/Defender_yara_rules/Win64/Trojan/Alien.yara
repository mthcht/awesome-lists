rule Trojan_Win64_Alien_EH_2147843310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alien.EH!MTB"
        threat_id = "2147843310"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mkdir C:\\Perform" ascii //weight: 1
        $x_1_2 = "powershell -inputformat none -outputformat none -NonInteractive -Command \"Add-MpPreference -ExclusionPath \"C:\\Perform\"" ascii //weight: 1
        $x_1_3 = "powershell -Command Add-MpPreference -ExclusionPath \"C:\\Perform\"" ascii //weight: 1
        $x_1_4 = "7za.exe x files.7z -aoa -p6H5d75Z8QwgEeQy" ascii //weight: 1
        $x_1_5 = ">nul ping -n 3 localhost" ascii //weight: 1
        $x_1_6 = "start C:\\Perform\\Setu64.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alien_MBFV_2147904965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alien.MBFV!MTB"
        threat_id = "2147904965"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 44 24 20 4c 8d 0d ?? ?? ?? ?? 33 d2 44 8d 42 01 48 8d 0d fe a6 01 00}  //weight: 5, accuracy: Low
        $x_1_2 = "DefaultBrowser" ascii //weight: 1
        $x_1_3 = "chrminst" ascii //weight: 1
        $x_1_4 = "amscloudhost.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alien_ARAA_2147905502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alien.ARAA!MTB"
        threat_id = "2147905502"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EMBEDDED\\STARTISALLRESET.XML" wide //weight: 2
        $x_2_2 = ">AUTOHOTKEY SCRIPT<" wide //weight: 2
        $x_2_3 = "FindResourceW" ascii //weight: 2
        $x_2_4 = {48 8d 15 d3 e0 0d 00 48 8b cb e8 cf 54 0c 00 85 c0 74 6a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Alien_GVK_2147960912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Alien.GVK!MTB"
        threat_id = "2147960912"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/v ShowSuperHidden /t REG_DWORD /d 2 /f" ascii //weight: 1
        $x_1_2 = "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/s,/c" ascii //weight: 1
        $x_3_3 = "://arkupdate.com/download/installer.msi" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

