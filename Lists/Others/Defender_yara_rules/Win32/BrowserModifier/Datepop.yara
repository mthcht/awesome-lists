rule BrowserModifier_Win32_Datepop_143786_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Datepop"
        threat_id = "143786"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Datepop"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "search.clickstory.co.kr/search_keyword.vht?" ascii //weight: 1
        $x_1_2 = {5c 50 6f 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "&cpspass=reload" ascii //weight: 1
        $x_1_4 = {61 70 70 2f 61 70 70 5f 70 6f 70 75 70 2e 70 68 70 3f [0-10] 6b 65 79 77 6f 72 64 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

