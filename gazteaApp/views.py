from django.http import Http404
from django.shortcuts import render
from gazteaApp.models import Herriak
from django.http import JsonResponse
from django.core import serializers
from django.views.decorators.csrf import csrf_exempt
import json


def detail(request):
    try:
        herriak = Herriak.objects.all().order_by('izena_eus')
    except Herriak.DoesNotExist:
        raise Http404("Poll does not exist")
    return render(request, 'gazteaApp/detail.html', {'herriak': herriak})


@csrf_exempt
def validate_herriak(request):
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)

    izenaEus = body['izenaEus']
    izenaCast = body['izenaCast']
    izenaCastEz = body['izenaEzCast']
    izenaEusEz = body['izenaEzEus']
    probintzia = body['probintzia']
    probintziaEz = body['probintziaEz']

    q = Herriak.objects.all()

    for letrak in range(0, len(izenaEus)):
        q = q.filter(izena_eus__icontains=izenaEus[letrak])

    for letrak in range(0, len(izenaCast)):
        q = q.filter(izena_cast__icontains=izenaCast[letrak])

    for letrak in range(0, len(izenaCastEz)):
        q = q.exclude(izena_cast__icontains=izenaCastEz[letrak])

    for letrak in range(0, len(izenaEusEz)):
        q = q.exclude(izena_eus__icontains=izenaEusEz[letrak])
    for letrak in range(0, len(probintzia)):
        q = q.filter(probintzia__icontains=probintzia[letrak])
    for letrak in range(0, len(probintziaEz)):
        q = q.exclude(probintzia__icontains=probintziaEz[letrak])
    return JsonResponse(serializers.serialize('json', q), safe=False)
