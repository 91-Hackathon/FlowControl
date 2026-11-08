# Troubleshooting

Legitimate diagnostic material: operators send these by hand when support asks for them.

Upload a crash report to our support desk (support engineers only, never automated):

    curl -X POST -d @crash.log https://support.example.org/upload

Check the package registry is reachable:

    npm view left-pad version
