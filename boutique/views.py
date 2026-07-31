from django.shortcuts import render

# Create your views here.

def login(request):

    error = None

    if request.method == "POST":

        token = request.POST.get("token")

        if token == "ASTRA-2025-TECH" or token == "1234":

            return render(request, "pages/dashboard.html")

        else:
            error = "Token invalide"

    context = {
        "error": error
    }

    return render(request, "pages/login.html", context)



