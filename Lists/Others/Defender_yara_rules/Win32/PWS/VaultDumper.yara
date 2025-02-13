rule PWS_Win32_VaultDumper_GG_2147828528_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VaultDumper.GG!MTB"
        threat_id = "2147828528"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VaultDumper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptedUsername" ascii //weight: 1
        $x_1_2 = "encryptedPassword" ascii //weight: 1
        $x_1_3 = "%s\\Mozilla\\Firefox\\profiles.ini" ascii //weight: 1
        $x_1_4 = "logins" ascii //weight: 1
        $x_1_5 = "hostname" ascii //weight: 1
        $x_1_6 = "SELECT * FROM moz_logins" ascii //weight: 1
        $x_1_7 = "SELECT * FROM logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

