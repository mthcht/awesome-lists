rule HackTool_Linux_DirbMem_A_2147805418_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/DirbMem.A!!DirbMem.A"
        threat_id = "2147805418"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "DirbMem"
        severity = "High"
        info = "DirbMem: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "By The Dark Raver" ascii //weight: 4
        $x_2_2 = "Specify your custom USER_AGENT." ascii //weight: 2
        $x_2_3 = "/usr/share/dirb/wordlists/vulns/" ascii //weight: 2
        $x_2_4 = "resume/dirlist.dump" ascii //weight: 2
        $x_2_5 = "resume/wordlist.dump" ascii //weight: 2
        $x_2_6 = "proxy_username:proxy_password" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

