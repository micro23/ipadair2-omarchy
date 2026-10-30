"""Post-install automatic native-root boot payload; never boot before install."""
from compose_installer_bootstrap import main
if __name__=='__main__':main(native=True)
