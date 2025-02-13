rule BrowserModifier_Win32_Chackill_143043_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Chackill"
        threat_id = "143043"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Chackill"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects\\" ascii //weight: 1
        $x_1_2 = {61 4b 69 6c 6c 65 72 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_3 = "DDD7FEE6-A953-0871-5DEC-BCF981AD7633" ascii //weight: 1
        $x_1_4 = "//vg.la/addurl.htm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

