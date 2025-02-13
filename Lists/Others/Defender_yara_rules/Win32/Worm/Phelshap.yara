rule Worm_Win32_Phelshap_A_2147683948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phelshap.A"
        threat_id = "2147683948"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phelshap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Process ID of 'shakhpel' is %d" ascii //weight: 1
        $x_1_2 = "No USB Drive" ascii //weight: 1
        $x_1_3 = "%s\\TightVNC\\vnc.dat" ascii //weight: 1
        $x_1_4 = "shell\\open\\command=tighVncSetup\\vnc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

