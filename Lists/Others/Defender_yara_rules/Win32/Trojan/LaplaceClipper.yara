rule Trojan_Win32_LaplaceClipper_NEAA_2147841215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LaplaceClipper.NEAA!MTB"
        threat_id = "2147841215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LaplaceClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "OSFRSCKT" ascii //weight: 5
        $x_5_2 = "BNKBPNHX" ascii //weight: 5
        $x_2_3 = "skipactivexreg" ascii //weight: 2
        $x_2_4 = "/bugcheckfull" ascii //weight: 2
        $x_2_5 = "/checkprotection" ascii //weight: 2
        $x_2_6 = "9/forcerun" ascii //weight: 2
        $x_2_7 = "3SOFTWARE\\WinLicense" ascii //weight: 2
        $x_2_8 = "Date: 03/19/09 22:5" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

