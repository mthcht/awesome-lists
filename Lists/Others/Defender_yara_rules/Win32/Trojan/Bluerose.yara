rule Trojan_Win32_Bluerose_2147748740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bluerose!MSR"
        threat_id = "2147748740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bluerose"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hacked by bluerose" wide //weight: 1
        $x_1_2 = "I will hack you with my 1s and 0s bitch" wide //weight: 1
        $x_1_3 = "c:\\Users\\Public\\brehrose.txt" wide //weight: 1
        $x_1_4 = "BLUEROSE TERMINATED YOUR COMPUTER" wide //weight: 1
        $x_1_5 = "BlueroseVirus.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

