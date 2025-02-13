rule Ransom_Linux_Sodinokibi_JJ_2147783553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Sodinokibi.JJ"
        threat_id = "2147783553"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "esxcli --formatter=csv --format-param=fields==" ascii //weight: 1
        $x_1_2 = "vm process list | awk -F " ascii //weight: 1
        $x_1_3 = "esxcli vm process kill --type=force --world-id=" ascii //weight: 1
        $x_1_4 = "Revix 1.1" ascii //weight: 1
        $x_1_5 = "!!!BY DEFAULT THIS SOFTWARE USES 50 THREADS!!!" ascii //weight: 1
        $x_1_6 = "Using silent mode, if you on esxi - stop VMs manualy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Linux_Sodinokibi_JK_2147784192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Sodinokibi.JK"
        threat_id = "2147784192"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc c1 e0 02 48 63 d0 48 8b 45 a8 48 01 c2 8b 45 fc 48 98 8b 44 85 b0 88 02 8b 45 fc c1 e0 02 48 98 48 8d 50 01 48 8b 45 a8 48 01 c2 8b 45 fc 48 98 8b 44 85 b0 c1 e8 08 88 02 8b 45 fc c1 e0 02 48 98 48 8d 50 02 48 8b 45 a8 48 01 c2 8b 45 fc 48 98 8b 44 85 b0 c1 e8 10 88 02 8b 45 fc c1 e0 02 48 98 48 8d 50 03 48 8b 45 a8 48 01 c2 8b 45 fc 48 98 8b 44 85 b0 c1 e8 18 88 02 83 45 fc 01}  //weight: 1, accuracy: High
        $x_1_2 = "LS0tPT09IFdlbGNvbWUuIEFnYWluLiA9PT0tLS0KClsrXSBXaGF0cyBIYXBwZW4" ascii //weight: 1
        $n_100_3 = "SecureVisor" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Linux_Sodinokibi_JL_2147795772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Sodinokibi.JL"
        threat_id = "2147795772"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Sodinokibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Error create note in dir %s" ascii //weight: 1
        $x_1_2 = "pkill" ascii //weight: 1
        $x_1_3 = {8b 55 f0 8b 45 c0 01 d0 c1 c0 07 89 c2 8b 45 e0 31 d0 89 45 e0 8b 55 e0 8b 45 f0 01 d0 c1 c0 09 89 c2 8b 45 d0 31 d0 89 45 d0 8b 55 d0 8b 45 e0 01 d0 c1 c0 0d 89 c2 8b 45 c0 31 d0 89 45 c0 8b 55 c0 8b 45 d0 01 d0 c1 c8 0e}  //weight: 1, accuracy: High
        $x_1_4 = "{\"ver\":%d,\"pk\":\"%s\",\"uid\":\"%s\",\"sk\":\"%s\",\"os\":\"%s\",\"ext\":\"%s\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

