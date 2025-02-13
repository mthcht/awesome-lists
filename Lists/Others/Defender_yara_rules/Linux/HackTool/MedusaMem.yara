rule HackTool_Linux_MedusaMem_A_2147805417_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MedusaMem.A!!MedusaMem.A"
        threat_id = "2147805417"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MedusaMem"
        severity = "High"
        info = "MedusaMem: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JoMo-Kun / Foofus Networks" ascii //weight: 2
        $x_2_2 = "# Medusa has finished (%s)" ascii //weight: 2
        $x_2_3 = "# Medusa v.%s (%s)" ascii //weight: 2
        $x_2_4 = "Total Passwords: [combo]" ascii //weight: 2
        $x_2_5 = "Total Users: [combo]" ascii //weight: 2
        $x_2_6 = ": File containing passwords to test" ascii //weight: 2
        $x_2_7 = "medusaConnectSSLInternal" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

