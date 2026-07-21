rule Trojan_Win64_CryptoSwap_AMTB_2147974186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoSwap!AMTB"
        threat_id = "2147974186"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoSwap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h1.eEkey///%25Viacgodnsudpftpssh::1setagevia204206304400500" ascii //weight: 1
        $x_1_2 = "transport is nilhost unreachableAlready ReportedMultiple ChoicesPayment RequiredUpgrade" ascii //weight: 1
        $x_1_3 = "\\Stat.com.exe.cmdpathallgallprootitabsbrkidledead is LEAFheapbase at Has  of ) =  <==GOGC] =  pc=+Inf-Inf: p=cas1c" ascii //weight: 1
        $x_3_4 = "q6mCnj0za1rChVShrWpg/y-37UgZxoTS6pXC4wlWF/AlrbVUc0ZC1e48a4uPnh/ogpyzXpn7GjkY1ObkrSO" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CryptoSwap_A_2147974187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptoSwap.A!AMTB"
        threat_id = "2147974187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptoSwap"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c ping 127.0.0.1 -n 2 > nul & del /f /q " ascii //weight: 1
        $x_1_2 = "e748f336d85ea5f9dcdf25d8f347a65b4cdf667600f02df6724a2af18a212d26b788a25086910cf3a903136968" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

