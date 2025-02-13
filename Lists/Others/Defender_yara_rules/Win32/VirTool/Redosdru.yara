rule VirTool_Win32_Redosdru_A_2147623135_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Redosdru.A"
        threat_id = "2147623135"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gh0st RAT" wide //weight: 1
        $x_1_2 = "GH0STC%sGH0STC" wide //weight: 1
        $x_1_3 = "%s - Key Logger" wide //weight: 1
        $x_1_4 = "A server has successfully been created!" wide //weight: 1
        $x_1_5 = "e:\\job\\gh0st\\Release\\gh0st.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

