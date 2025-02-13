rule Trojan_MSIL_RelineStealer_FM_2147818352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RelineStealer.FM!MTB"
        threat_id = "2147818352"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".pdb" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "Generate256BitsOfRandomEntropy" ascii //weight: 1
        $x_1_6 = "SoDOVPNSRzbecrB" ascii //weight: 1
        $x_1_7 = "vHaebUmaSFBbzkf" ascii //weight: 1
        $x_1_8 = "Reverse" ascii //weight: 1
        $x_1_9 = "InvokeMember" ascii //weight: 1
        $x_1_10 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RelineStealer_FO_2147818354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RelineStealer.FO!MTB"
        threat_id = "2147818354"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RelineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.ip.sb/ip" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Clients\\StartMenuInternet" ascii //weight: 1
        $x_1_3 = "{0}\\FileZilla\\recentservers.xml" ascii //weight: 1
        $x_1_4 = "user.config" ascii //weight: 1
        $x_1_5 = "cookies.sqlite" ascii //weight: 1
        $x_1_6 = "GetLogicalDrives" ascii //weight: 1
        $x_1_7 = "FromBase64" ascii //weight: 1
        $x_1_8 = "Profile_encrypted_value" ascii //weight: 1
        $x_1_9 = "waasflleasft.datasf" ascii //weight: 1
        $x_1_10 = "AppData\\Roaming\\TReplaceokReplaceenReplaces.tReplacext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

