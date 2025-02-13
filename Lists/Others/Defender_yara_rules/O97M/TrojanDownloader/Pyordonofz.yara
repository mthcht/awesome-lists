rule TrojanDownloader_O97M_Pyordonofz_2147712063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Pyordonofz"
        threat_id = "2147712063"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Pyordonofz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (qsn.vfq.Text & glzehskiqocvgqdf)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Pyordonofz_2147712063_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Pyordonofz"
        threat_id = "2147712063"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Pyordonofz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "h1UtYtRp:Y/4k/XgnRlX1n4tLhbk.kLckoRm/1iLRma1LgUe/4Umikckr1LosRoX4ftX.1kpXng4" ascii //weight: 1
        $x_1_2 = "4poLLwLerksKLhUelUlR.1Ke4xXe k-KYEXxeRXc4utXi1Ron1UPoklKikcLLy 4RBkyp1Ras1Ls" ascii //weight: 1
        $x_1_3 = "Shell (rbl.bne.Text & gqqbcbfdapunoinq)" ascii //weight: 1
        $x_1_4 = "Shell (ssz.dpf.Text & mczpjwmfgmxiklvg)" ascii //weight: 1
        $x_1_5 = "\"Berrtomttoel(ws.oe)/t.ee)OfW:w gSd.pi([Ng.mtj.Crtenoh.nechiTapmemle'-tWnc;/ Pn.RbaSGn$ty.SFlNSeiEepeIlimwim]D'eteped)" ascii //weight: 1
        $x_1_6 = "\"f91t.exe','%TMP%\\qweqwe.exe');\"" ascii //weight: 1
        $x_1_7 = "\"/lwedbUrc)gN h.xpbP/ikatteDeene/ao3te'n |'teteX:lQpnot.Kewnro-YSjiit (eitWssCx/exs)p.o(\"" ascii //weight: 1
        $x_1_8 = "Jkx61qahP = StrConv(etA0gU(QoRe4f1 & QeiaTVr & i7EHGuB3 & I846s & XoNbHyhp & cGwOaRzq & u3Xd9fwZF & y7tmYI6r5 & gwfIi6jS), vbUnicode)" ascii //weight: 1
        $x_1_9 = "Q3lkMg6La = \"DovL3d3dy5sb21lbmEuZXMvaTJpL2luYy9yZXF1ZXN0L3hzY3V3YWR4Z2svJy5TcGxpdCgnLCcpOyRuYW1lID0gJHJhbmRvbS5uZXh0KDE\"" ascii //weight: 1
        $x_1_10 = "ko2Pv = sBb8n & lRLQgu & aHiBP & saOI29R & AMjNvhuX & ppxrAvFS & N4RoMf & qQtbfa" ascii //weight: 1
        $x_1_11 = "(czhtGrd).Run$ rrpGwAG + DfSgUYAGwWY + PxhprVMe +" ascii //weight: 1
        $x_1_12 = {2b 27 68 74 74 70 3a 2f 2f 72 6f 6d 66 75 6c 2e 63 6f 6d 2f [0-16] 27 2b 24}  //weight: 1, accuracy: Low
        $x_1_13 = "(Nhy0Objhcw#T|uuen0Ohv/ZecFojfnu*1EpyomqdgFimg+'hwuq;/2drfuqsffglm0wrr2aenlo1qjs@h?2" ascii //weight: 1
        $x_1_14 = "+Oew.Odmhfw\"\"U|uufn1Ofu/ZgcFojgnu,.EoynlpbgGknh+)hwvr;0/whdobjm0svpsxqs.rrj0hd|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

