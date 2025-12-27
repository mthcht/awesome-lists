rule Backdoor_Script_RogueSpy_F_2147945894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Script/RogueSpy.F!dha"
        threat_id = "2147945894"
        type = "Backdoor"
        platform = "Script: "
        family = "RogueSpy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl.exe -x" wide //weight: 1
        $x_1_2 = "socks5h://127.0.0.1:9050 http://" wide //weight: 1
        $x_1_3 = ".onion" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Script_RogueSpy_E_2147946072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Script/RogueSpy.E!dha"
        threat_id = "2147946072"
        type = "Backdoor"
        platform = "Script: "
        family = "RogueSpy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vz5mhe7jmjt7rgiq7uhgmemtszfehlmjhhcue5zz3onhtlv3mflhwvid.onion" wide //weight: 1
        $x_1_2 = "acfnczhyzlhvfk5bhyuuqymmv5vak4xqxqpgamrjeh2wxxia7movbzyd.onion" wide //weight: 1
        $x_1_3 = "2zilmiystfbjib2k4hvhpnv2uhni4ax5ce4xlpb7swkjimfnszxbkaid.onion" wide //weight: 1
        $x_1_4 = "i2rgcvog6cypjohfzfzw3d5kqgoobkzlbchsdxx4gm7lyaxn5nfp6bid.onion" wide //weight: 1
        $x_1_5 = "zk3b4yq6zao7mhoyyfesq2y6ls2k6cia35jwjbiqe6fyd5cji5tsweyd.onion" wide //weight: 1
        $x_1_6 = "n6b6j4vlkc4ak343j4fmuwmosxtwrft6bph5s5562lefji4a475smuad.onion" wide //weight: 1
        $x_1_7 = "qqdd4drbvk3yuocystnqyonb26yo7kosfraotartvdcro6i57ausykqd.onion" wide //weight: 1
        $x_1_8 = "4epv34xjukr5y2zhhiztsr5fvshyig6hw6iw3w36xwcuaxcjdumy2uid.onion" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

