rule Trojan_Win32_BlackPunisher_YAA_2147922428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackPunisher.YAA!MTB"
        threat_id = "2147922428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackPunisher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BlackPunisherExclu" ascii //weight: 1
        $x_1_2 = "self_deleting_script.vbs" ascii //weight: 1
        $x_1_3 = "sync\\reentrant_lock.rs" ascii //weight: 1
        $x_1_4 = ".doc.docx.xls.xlsx.ppt.pptx.pst.ost.msg.eml.vsd.vsdx.txt.csv.rtf.123.wks.wk1.pdf." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

