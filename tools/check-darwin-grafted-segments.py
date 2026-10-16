from pathlib import Path


root = Path(__file__).resolve().parent.parent / "subprojects/frida-gum/gum"
grafter = (root / "gumdarwingrafter.c").read_text(encoding="utf-8")
interceptor = (root / "backend-arm64/guminterceptor-arm64.c").read_text(encoding="utf-8")

assert 'g_str_has_prefix (segment->name, "__RLY_")' in grafter
assert 'g_snprintf (seg.segname, sizeof (seg.segname), "__RLY_TEXT%u", j)' in grafter
assert 'g_snprintf (seg.segname, sizeof (seg.segname), "__RLY_DATA%u", j)' in grafter
assert 'g_str_has_prefix (sc->segname, "__RLY_DATA")' in interceptor
assert "__FRIDA_" not in grafter
assert "__FRIDA_DATA" not in interceptor

print("Darwin graft segment producers and consumers share neutral names")
