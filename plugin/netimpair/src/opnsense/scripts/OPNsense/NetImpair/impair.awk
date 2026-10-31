# Usage: awk -f impair.awk netimpair.conf dnctl.conf
# netimpair.conf lines: <pipe number> <delay ms or -> <loss fraction>
FNR == NR {
    if (NF == 3) { delay[$1] = $2; loss[$1] = $3 }
    next
}
$1 == "pipe" && $3 == "config" && ($2 in loss) {
    n = $2
    if (delay[n] != "-") {
        gsub(/ delay [0-9]+/, "")
        $0 = $0 " delay " delay[n]
    }
    if (loss[n] + 0 > 0) {
        $0 = $0 " plr " loss[n]
    }
}
{ print }
