rule Trojan_X97M_LionWolf_A_2147817765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:X97M/LionWolf.A"
        threat_id = "2147817765"
        type = "Trojan"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "LionWolf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "libkernel32aliascreateprocessa" ascii //weight: 5
        $x_5_2 = "libkernel32aliascreateremotethread" ascii //weight: 5
        $x_5_3 = "libkernel32aliasvirtualallocex" ascii //weight: 5
        $x_5_4 = "libkernel32aliaswriteprocessmemory" ascii //weight: 5
        $x_1_5 = "namespacenetbiosname" ascii //weight: 1
        $x_1_6 = "getobjectldaprootdse" ascii //weight: 1
        $x_1_7 = "createobjectmsxml2domdocument" ascii //weight: 1
        $x_1_8 = "environwindir" ascii //weight: 1
        $x_1_9 = "environprogramw6432" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 3 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

