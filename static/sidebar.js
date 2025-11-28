// Toggle del submenu "Estadísticas"
(function(){
  const box = document.querySelector('.stats-menu');
  const btn = document.querySelector('.stats-toggle');
  if(!box || !btn) return;

  btn.addEventListener('click', ()=> {
    box.classList.toggle('is-open');
    const icon = btn.querySelector('.icon i');
    if(icon){ icon.classList.toggle('fa-chevron-down'); icon.classList.toggle('fa-chevron-up'); }
  });

  // Si estamos en /stats, abrir por defecto
  if (location.pathname === '/stats') {
    box.classList.add('is-open');
    const icon = btn.querySelector('.icon i');
    if(icon){ icon.classList.remove('fa-chevron-down'); icon.classList.add('fa-chevron-up'); }
  }
})();
