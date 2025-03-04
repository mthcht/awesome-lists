rule Ransom_Win32_Wannacash_PA_2147746015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wannacash.PA!MTB"
        threat_id = "2147746015"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wannacash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "].wannacash .zip" wide //weight: 1
        $x_1_2 = "ulitochkimoi:" wide //weight: 1
        $x_1_3 = "justsurrender@rape.lol" wide //weight: 1
        $x_1_4 = ".doc .docx .xls .xlsx .xlst .ppt .pptx .accdb .rtf .pub .epub .pps .ppsm .pot .pages .odf .odt .ods .pdf .djvu .html .rtf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Wannacash_SA_2147748548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wannacash.SA!MSR"
        threat_id = "2147748548"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wannacash"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "noallpossible@cock.li .happy new year" wide //weight: 1
        $x_1_2 = "ZXNldHNodXR1cGZ1Y2t1cA==" wide //weight: 1
        $x_1_3 = "XNC60LDQuiDRgNCw0YHRiNC40YTRgNC+0LLQsNGC0Ywg0YTQsNC50LvRiy50eHQ=" wide //weight: 1
        $x_1_4 = "4pWRICDQoyDQktCQ0KEg0LXRgdGC0Ywg0YDQvtCy0L3QviA3INC00L3QtdC5INC90LAg0YHQstGP0LfRjCDRgdC+INC80L3QvtC5LiA=" wide //weight: 1
        $x_1_5 = "wannacash\\LockBox" wide //weight: 1
        $x_1_6 = "TW96aWxsYS81LjAgKExpbnV4OyBVOyBBbmRyb2lkI" wide //weight: 1
        $x_1_7 = "aHR0cHM6Ly9pcGxvZ2dlci5vcmc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

