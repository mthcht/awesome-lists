rule Worm_MSIL_FileCoder_AC_2147962379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/FileCoder.AC!AMTB"
        threat_id = "2147962379"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DeploySpyware" ascii //weight: 1
        $x_1_2 = "TRUEW0RM.pdb" ascii //weight: 1
        $x_1_3 = "start TrueWorm" ascii //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TrueWorm" ascii //weight: 1
        $x_1_5 = "WiFi Credentials" ascii //weight: 1
        $x_1_6 = "TRUE_W0RM_ACTIVATED && echo SYSTEM ENCRYPTED && echo DATA STOLEN AND SENT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

