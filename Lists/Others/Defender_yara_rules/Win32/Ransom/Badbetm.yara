rule Ransom_Win32_Badbetm_PA_2147764687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Badbetm.PA!MTB"
        threat_id = "2147764687"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Badbetm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOW TO DECRYPT YOUR FILES" ascii //weight: 1
        $x_1_2 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "Local\\RustBacktraceMutex" ascii //weight: 1
        $x_1_4 = "\\Recover files.hta" ascii //weight: 1
        $x_1_5 = ".CRPTD" ascii //weight: 1
        $x_1_6 = "wevtutil cl \"%1\"\\start_after.bat" ascii //weight: 1
        $x_1_7 = "\\release\\deps\\untitled.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

