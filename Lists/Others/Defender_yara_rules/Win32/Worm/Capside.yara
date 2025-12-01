rule Worm_Win32_Capside_ARR_2147958565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Capside.ARR!MTB"
        threat_id = "2147958565"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Capside"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Vtx = Replace(Vtx, \"$\", Chr(34)): Document.Write (Vtx) & vbCrLf & Capside" ascii //weight: 10
        $x_5_2 = "Ec = Ec & Chr(Ck Xor 7)" ascii //weight: 5
        $x_12_3 = "Vtx=\"<object style=$cursor:cross-hair$ classid=$clsid:22222222-2222-2222-2222$  CODEBASE=$mhtml:\"&Vpt&\"!file:///Capside.exe$></object>\"" ascii //weight: 12
        $x_8_4 = "Capside.exe" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

