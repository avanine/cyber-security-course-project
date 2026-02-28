from django.http import HttpResponseRedirect
from django.urls import reverse
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.core.cache import cache

from .models import Choice, Question


def index(request):
    latest_question_list = Question.objects.order_by('-pub_date')[:5]
    context = {'latest_question_list': latest_question_list}
    return render(request, 'polls/index.html', context)

def detail(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    return render(request, 'polls/detail.html', {'question': question})

def results(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    return render(request, 'polls/results.html', {'question': question})

def vote(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    try:
        selected_choice = question.choice_set.get(pk=request.POST['choice'])
    except (KeyError, Choice.DoesNotExist):
        # Redisplay the question voting form.
        return render(request, 'polls/detail.html', {
            'question': question,
            'error_message': "You didn't select a choice.",
        })
    else:
        selected_choice.votes += 1
        selected_choice.save()
        # Always return an HttpResponseRedirect after successfully dealing
        # with POST data. This prevents data from being posted twice if a
        # user hits the Back button.
        return HttpResponseRedirect(reverse('polls:results', args=(question.id,)))


def register(request):
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')

        if User.objects.filter(username=username).exists():
            return render(request, 'polls/register.html', {
                'error': 'Username already taken',
            })

        user = User(username=username)
        # A02:2021 Cryptographic Failures: password is stored in plaintext without hashing
        user.password = password
        # A02 FIX: use set_password which hashes the password properly
        # user.set_password(password)
        user.save()
        
        return redirect('polls:index')

    return render(request, 'polls/register.html')


MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        ip = request.META.get('REMOTE_ADDR', 'unknown')

        # A07:2021 Identification and Authentication Failures: no rate limiting, attacker can brute-force passwords
        # A07 FIX: rate limiting by IP and username
        # key = f'login_attempts:{ip}:{username}'
        # attempts = cache.get(key, 0)
        # if attempts >= MAX_ATTEMPTS:
        #     return render(request, 'polls/login.html', {
        #         'error': 'Too many attempts. Try again later.',
        #     })

        try:
            user = User.objects.get(username=username)
            if user.password == password:
                auth_login(request, user)
                # A07 FIX: reset on success
                # cache.delete(key)
                return redirect('polls:index')
            # A02 FIX: when using set_password, use check_password instead:
            # if user.check_password(password):
            #     auth_login(request, user)
            #     return redirect('polls:index')
        except User.DoesNotExist:
            pass

        # A07 FIX: increment attempts on failure and expire after window
        # cache.set(key, attempts + 1, timeout=WINDOW_SECONDS)

        return render(request, 'polls/login.html', {
            'error': 'Wrong username or password',
        })

    return render(request, 'polls/login.html')


def logout_view(request):
    auth_logout(request)
    return redirect('polls:login')